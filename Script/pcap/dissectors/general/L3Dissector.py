from abc import ABC, abstractmethod

class L3Dissector(ABC):
    @abstractmethod
    def get_upper_layer_protocol(self) -> int: ...