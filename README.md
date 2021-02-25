# d4ft
A P2P file transfer program utilizing py7zr and raw TCP.

Specification:
```
            - Handshake:
44 34 46 54     - 4 byte header (D4FT)
__              - 1 byte mode switch:
                    - 41 -> A (neither compression or encryption)
                    - 42 -> B (compression, no encryption)
                    - 43 -> C (compression and encryption)
                    - 54 -> T (text only mode)
                    - 55 -> U (encrypted text)
__ __ __ __     - 4 bytes (length of the file to be sent)
__*32           - 32 byte SHA-256 hash
__*?            - filename (any length, only in 'A' mode)
            - Response:
44 34 46 54     - 4 byte header (D4FT)
__              - 1 byte response (lowercase of mode switch that was sent)
                    - 61 -> a
                    - 62 -> b
                    - 63 -> c
                    - 74 -> t
                    - 75 -> u
            - Send data
            - Ending packet:
44 34 46 54     - 4 byte header (D4FT)
44 4F 4E 45     - 4 bytes (DONE)
            - Response:
44 34 46 54     - 4 byte header (D4FT)
__              - 1 byte confirmation:
                    - 52 -> R (received correctly)
                    - 53 -> S (try again)
            - Sender responds depending on the correctness of the file length
                - If correct, echoes back the header and length
                - If incorrect, resends the initial connection packet and restarts from there
```
