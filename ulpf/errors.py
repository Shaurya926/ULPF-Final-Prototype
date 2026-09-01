class ULPFError(Exception):
    """Base exception for the ULPF core engine."""


class DetectionError(ULPFError):
    pass


class ParserError(ULPFError):
    pass


class MappingError(ULPFError):
    pass


class ContractError(ULPFError):
    pass


class SecurityError(ULPFError):
    pass
