"""RAIL - Risk-Adaptive Integrity Layering.

A software-based data-diode / cross-domain transfer stack that implements the
six-stage pipeline (S1-S6) described in the paper "Software-Based Data Diodes
for Trusted Network Integration: A Survey and a Risk-Adaptive Multilayer
Architecture".

The package is split so that each stage maps to one module:

    S1  protocol_break.ProtocolBreak.extract        (protocol separation)
    S2  inspection.engine.InspectionEngine          (layered DPI, Eq. 1)
    S3  chunker + hashchain + merkle + session       (adaptive integrity, Eq.2/3)
    S4  fec.FEC.encode  + sender.SenderGateway        (FEC + one-way send)
    S4' fec.FEC.decode  + receiver.ReceiverGateway    (FEC decode)
    S5  crypto.verify + merkle/hashchain recompute    (integrity verification)
    S6  protocol_break.ProtocolBreak.reoriginate      (re-origination)
"""

__version__ = "1.0.0"
