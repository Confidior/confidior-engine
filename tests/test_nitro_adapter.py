from src.core.taxonomy import NodeType, Platform
from src.ingest.adapters.nitro import parse_nitro_attestation, verify_nitro_attestation


def test_parse_real_nitro_attestation():
    with open("tests/fixtures/nitro/aws-c6g-nitro-attestation.hex") as f:
        hex_data = f.read()

    node = parse_nitro_attestation(hex_data)

    assert node.node_type == NodeType.QUOTE
    assert node.platform == Platform.AWSNitro
    assert node.measurement == "cca6d8f389f3215631a31901469e63bef16435fdd2ffcbc09aad18872eb77229e0a602891cb7a1b9a42fd5b97eb0362a"
    assert node.metadata["pcr0"] == "cca6d8f389f3215631a31901469e63bef16435fdd2ffcbc09aad18872eb77229e0a602891cb7a1b9a42fd5b97eb0362a"
    assert node.metadata["pcr1"] == "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03"
    assert node.metadata["pcr2"] == "c75dbe4d9423e5dfb6785c30805c408e20b792fbe5dfd2de7a3311e6d718ff9f52813005b667fcc53d8a30cbea4f9b19"
    assert node.metadata["module_id"] == "i-01067cfa560f27f3d-enc019f3e452b6927d3"
    assert node.metadata["timestamp"] == 1783456414261
    assert node.metadata["digest"] == "SHA384"
    assert "nonce" in node.metadata


def test_verify_real_nitro_passes():
    with open("tests/fixtures/nitro/aws-c6g-nitro-attestation.hex") as f:
        hex_data = f.read()

    result = verify_nitro_attestation(hex_data)

    # Should pass: cert chain verifies and COSE signature validates
    assert result["valid"] is True
    assert result["error"] is None
