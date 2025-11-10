import numpy as np
import time
import json
from datetime import datetime
import random

class SmartMeterSimulator:
    """Simulates realistic smart meter readings"""
    
    def __init__(self, meter_id, base_voltage=230.0, base_current=10.0, frequency=50.0):
        self.meter_id = meter_id
        self.base_voltage = base_voltage
        self.base_current = base_current
        self.frequency = frequency
        self.reading_count = 0
        
    def generate_reading(self):
        """
        Generate realistic smart meter reading with variations
        Returns: Dictionary with meter data
        """
        self.reading_count += 1
        
        # Add realistic variations and noise
        voltage = self.base_voltage + np.random.normal(0, 2.5)  # ±2.5V variation
        current = self.base_current + np.random.normal(0, 1.0)  # ±1A variation
        frequency = self.frequency + np.random.normal(0, 0.1)   # ±0.1Hz variation
        
        # Calculate power metrics
        power_factor = np.random.uniform(0.85, 0.95)
        active_power = voltage * current * power_factor  # Watts
        reactive_power = voltage * current * np.sqrt(1 - power_factor**2)  # VAR
        apparent_power = voltage * current  # VA
        
        # Add time-of-day patterns (higher consumption during evening)
        hour = datetime.now().hour
        if 18 <= hour <= 22:  # Evening peak
            active_power *= np.random.uniform(1.3, 1.8)
        elif 0 <= hour <= 6:  # Night low
            active_power *= np.random.uniform(0.4, 0.7)
        
        reading = {
            'meter_id': self.meter_id,
            'timestamp': datetime.now().isoformat(),
            'reading_number': self.reading_count,
            'voltage': round(voltage, 2),
            'current': round(current, 2),
            'frequency': round(frequency, 2),
            'active_power': round(active_power, 2),
            'reactive_power': round(reactive_power, 2),
            'apparent_power': round(apparent_power, 2),
            'power_factor': round(power_factor, 3)
        }
        
        return reading
    
    def get_data_vector(self, reading):
        """
        Extract numerical values for encryption
        Returns: List of float values
        """
        return [
            reading['voltage'],
            reading['current'],
            reading['frequency'],
            reading['active_power'],
            reading['reactive_power'],
            reading['apparent_power'],
            reading['power_factor']
        ]
