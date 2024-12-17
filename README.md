#tfhe-aes
tFHE implementation of tfhe-aes


# Workflow

1. Planning and Preperation Phase
[X] Set up TOML File
[ ] Split up work for the initial functioning prototype
[ ] Read up on documentation, tfhe methods, and possible optimisations, expansions
[ ] Start small tasks (import modules, create basic structs, commandline parser, etc)

2. Creating firts prototype
[ ]Create first prototype:
    - [ ] Submethods for KeyExpansion
    - [ ] KeyExpansion
    - [ ] more stuff to come soon



# Roadmap

15/12: I started reading up on the basic operations for KeyExpansion, and I should be able to implement a form of it by maybe tomorrow? I think you guys can start working on the other 4 steps of AES Cipher being, MixColumns, RotWord etc and converting them into FHE versions. I think for optimisations, use as few CMux as possible, and instead use basic operations like bit shifting etc, and no complex structures. 

16/12 Did not manage to do 
