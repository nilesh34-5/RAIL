"""Stage S2 - layered deep packet / object inspection.

Each detector is an independent module returning a confidence s_i(O) in [0,1].
The engine combines them with Noisy-OR (Eq. 1) and quantises the result.
"""
