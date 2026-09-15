object "OpaqueYul" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            // Family: opaque_ir. Regex IR is blind. Specialized synths skip;
            // fuzz still runs. Not a Solidity hidden-set shape.
            calldatacopy(0, 0, calldatasize())
            sstore(0, calldataload(0))
        }
    }
}
