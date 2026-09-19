#!/usr/bin/env python3
"""Exercise the running Docker web service through HTTP and a real browser.

The host needs Playwright and Chromium; no browser dependency enters the image.
Every proof comes from the running image. There are no intercepted API responses.
"""
import argparse
import json
import re
import time
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def request(base, path):
    with urlopen(base + path, timeout=15) as response:
        return response.status, response.headers.get_content_type(), response.read()


def check_http(base):
    # Compose's healthcheck is also exercised in CI; this permits direct reuse
    # of this script after `docker run ... web` on a developer machine.
    deadline = time.monotonic() + 90
    while True:
        try:
            status, content_type, body = request(base, "/api/health")
            health = json.loads(body)
            require(status == 200 and content_type == "application/json", "health endpoint is not JSON/200")
            require(health.get("ok") is True, f"runtime not ready: {health}")
            break
        except (URLError, TimeoutError, AssertionError) as exc:
            if time.monotonic() >= deadline:
                raise AssertionError("Docker web service did not become ready") from exc
            time.sleep(1)
    print(json.dumps({"case": "health", "response": health}), flush=True)

    for path in ("/", "/index.html", "/analysis", "/analysis.html", "/track04.html"):
        status, content_type, body = request(base, path)
        require(status == 200 and content_type == "text/html", f"missing HTML route: {path}")
        require(b"TRUST404" in body, f"unexpected static content: {path}")
    status, _, body = request(base, "/METHOD.md")
    require(status == 200 and len(body) > 100, "METHOD.md deliverable is missing")
    status, _, body = request(base, "/vendor/jszip.min.js")
    require(status == 200 and b"JSZip" in body, "offline ZIP upload dependency is missing")
    _, _, body = request(base, "/api/prove")
    require({"OpenVault", "SafeVault"}.issubset(json.loads(body)["targets"]), "built-in targets are missing")

    for path in ("/not-a-page", "/agent/agent.py", "/.git/config"):
        try:
            request(base, path)
        except HTTPError as exc:
            require(exc.code == 404, f"unexpected status for {path}: {exc.code}")
        else:
            raise AssertionError(f"private/unknown path was served: {path}")
    print(json.dumps({"case": "http-routes", "passed": True}), flush=True)


def check_proof(data, expected, label):
    """An error or unexecuted negative must never pass as a healthy control."""
    require(isinstance(data, dict), f"{label}: response is not an object")
    require(not data.get("error"), f"{label}: API error: {data.get('error')}")
    require(data.get("proven") is expected, f"{label}: expected proven={expected}, got {data.get('proven')}")
    steps = {step["step"]: step for step in data.get("steps", [])}
    require({"deploy_target", "run_exploit", "verify"}.issubset(steps), f"{label}: EVM execution evidence missing")
    deployed = steps["deploy_target"]
    run = steps["run_exploit"]
    verified = steps["verify"]
    require(re.fullmatch(r"0x[0-9a-fA-F]{40}", deployed.get("address", "")), f"{label}: target not deployed")
    require(re.fullmatch(r"0x[0-9a-fA-F]{40}", run.get("exploit_address", "")), f"{label}: exploit not deployed")
    require(deployed.get("checkAll_before", {}).get("allHold") is True, f"{label}: baseline was not healthy")
    require(verified.get("checkAll_after", {}).get("allHold") is (not expected), f"{label}: post-execution invariant mismatch")
    require(bool(data.get("firstViolated")) is expected, f"{label}: violated predicate mismatch")
    require(bool(data.get("exploit_src")), f"{label}: generated exploit source missing")
    print(json.dumps({"case": label, "proven": data["proven"], "predicate": data.get("firstViolated")}), flush=True)


def check_browser(base, artifacts):
    from playwright.sync_api import sync_playwright, expect

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        context.tracing.start(screenshots=True, snapshots=True, sources=True)
        page = context.new_page()
        page.set_default_timeout(15_000)
        script_errors = []
        page.on("pageerror", lambda error: script_errors.append(str(error)))
        try:
            page.goto(base, wait_until="domcontentloaded")
            expect(page.locator(".runbtn")).to_have_count(12)
            page.screenshot(path=str(artifacts / "home-desktop.png"))

            for name, expected in (("OpenVault", True), ("SafeVault", False)):
                def matches(response):
                    parsed = urlparse(response.url)
                    return parsed.path == "/api/prove" and parse_qs(parsed.query).get("target") == [name]

                with page.expect_response(matches, timeout=180_000) as pending:
                    page.locator(f'.runbtn[data-t="{name}"]').click()
                response = pending.value
                require(response.ok, f"{name}: HTTP {response.status}")
                data = response.json()
                (artifacts / f"{name}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                check_proof(data, expected, name)
                expect(page.locator(f"#v-{name}")).to_have_text("PROVEN" if expected else "NOT PROVEN")
                button = page.locator(f'.runbtn[data-t="{name}"]')
                expect(button).to_be_enabled()
                button.locator("xpath=../..").screenshot(path=str(artifacts / f"{name}.png"))

            # Real file inputs, file-reading handlers, JSON submission, compilation,
            # EVM execution, and UI rendering are all part of this custom proof.
            fixture = ROOT / "targets" / "ReentrantVault"
            source = (fixture / "src" / "ReentrantVault.sol").read_text(encoding="utf-8")
            invariants = (fixture / "Invariants.sol").read_text(encoding="utf-8")
            page.locator("#f-contract").set_input_files(str(fixture / "src" / "ReentrantVault.sol"))
            page.locator("#f-inv").set_input_files(str(fixture / "Invariants.sol"))
            expect(page.locator("#c-contract")).to_have_value(source)
            expect(page.locator("#c-inv")).to_have_value(invariants)
            # Re-upload as ZIP to exercise the locally bundled JSZip loader too.
            archive = artifacts / "upload-fixture.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("src/ReentrantVault.sol", source)
            page.locator("#c-contract").fill("")
            page.locator("#f-contract").set_input_files(str(archive))
            expect(page.locator("#c-contract")).to_have_value(source)
            page.locator("#c-name").fill("ReentrantVault")
            # This browser path deploys the target directly; there is no Setup file upload.
            manifest = json.loads((fixture / "manifest.json").read_text(encoding="utf-8"))
            manifest["deploy"].pop("setup", None)
            page.locator("details.man > summary").click()
            page.locator("#c-man").fill(json.dumps(manifest))
            with page.expect_response(lambda response: urlparse(response.url).path == "/api/prove" and response.request.method == "POST", timeout=180_000) as pending:
                page.locator("#runCustom").click()
            response = pending.value
            require(response.ok, f"custom upload: HTTP {response.status}")
            data = response.json()
            (artifacts / "custom-upload.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            check_proof(data, True, "custom-upload")
            expect(page.locator("#v-custom")).to_have_text("PROVEN")
            expect(page.locator("#runCustom")).to_be_enabled()
            page.locator("#customCard").screenshot(path=str(artifacts / "custom-upload.png"))

            page.set_viewport_size({"width": 390, "height": 844})
            page.goto(base, wait_until="domcontentloaded")
            expect(page.locator("#runAll")).to_be_visible()
            require(page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), "mobile page overflows horizontally")
            page.screenshot(path=str(artifacts / "home-mobile.png"))
            require(not script_errors, f"browser JavaScript errors: {script_errors}")
        except Exception:
            page.screenshot(path=str(artifacts / "failure.png"), full_page=True)
            raise
        finally:
            (artifacts / "browser-errors.json").write_text(json.dumps(script_errors, indent=2), encoding="utf-8")
            context.tracing.stop(path=str(artifacts / "browser-trace.zip"))
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--artifacts", type=Path, default=Path("docker-web-artifacts"))
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    base = args.base_url.rstrip("/")
    check_http(base)
    check_browser(base, args.artifacts)
    print(json.dumps({"case": "docker-web", "passed": True, "skipped": 0}), flush=True)


if __name__ == "__main__":
    main()
