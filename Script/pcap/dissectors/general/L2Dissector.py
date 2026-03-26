from abc import ABC, abstractmethod

class L2Dissector(ABC):
    @abstractmethod
    def get_upper_layer_type(self) -> int: ...