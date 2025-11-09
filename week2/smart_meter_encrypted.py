import time
import json
import os
from datetime import datetime
from ckks_context import CKKSContext
from smart_meter_simulator import SmartMeterSimulator

class EncryptedSmartMeter:
    """Smart meter that encrypts data before transmission"""
    
    def __init__(self, meter_id, ckks_context):
        self.meter_id = meter_id
        self.simulator = SmartMeterSimulator(meter_id)
        self.ckks = ckks_context
        self.log_dir = f"logs/meter_{meter_id}"
        os.makedirs(self.log_dir, exist_ok=True)
        
    def collect_and_encrypt(self):
        """Generate reading and encrypt it"""
        # Generate raw reading
        reading = self.simulator.generate_reading()
        
        # Extract numerical data for encryption
        data_vector = self.simulator.get_data_vector(reading)
        
        # Encrypt the data vector
        start_time = time.time()
        encrypted_data = self.ckks.encrypt_vector(data_vector)
        encryption_time = (time.time() - start_time) * 1000  # Convert to ms
        
        # Create payload
        payload = {
            'meter_id': self.meter_id,
            'timestamp': reading['timestamp'],
            'reading_number': reading['reading_number'],
            'encrypted_data': encrypted_data.serialize().hex(),  # Hex string for transport
            'encryption_time_ms': round(encryption_time, 2),
            'data_fields': ['voltage', 'current', 'frequency', 'active_power', 
                           'reactive_power', 'apparent_power', 'power_factor']
        }
        
        # Log the activity
        self._log_reading(reading, encryption_time)
        
        print(f"[{reading['timestamp']}] Meter {self.meter_id} - Reading #{reading['reading_number']}")
        print(f"  → Active Power: {reading['active_power']:.2f}W")
        print(f"  → Voltage: {reading['voltage']:.2f}V, Current: {reading['current']:.2f}A")
        print(f"  → Encryption Time: {encryption_time:.2f}ms")
        print(f"  → Encrypted Size: {len(payload['encrypted_data'])} bytes")
        
        return payload, reading
    
    def _log_reading(self, reading, encryption_time):
        """Log reading to file"""
        log_file = os.path.join(self.log_dir, f"readings_{datetime.now().strftime('%Y%m%d')}.json")
        
        log_entry = {
            **reading,
            'encryption_time_ms': round(encryption_time, 2)
        }
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def run_continuous(self, interval_seconds=60):
        """Run meter continuously with specified interval"""
        print(f"\n{'='*60}")
        print(f"🔒 ENCRYPTED SMART METER - ID: {self.meter_id}")
        print(f"{'='*60}")
        print(f"Generating encrypted readings every {interval_seconds} seconds...")
        print(f"Press Ctrl+C to stop\n")
        
        try:
            while True:
                payload, reading = self.collect_and_encrypt()
                print("-" * 60)
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print(f"\n\n✓ Meter {self.meter_id} stopped. Total readings: {self.simulator.reading_count}")


def main():
    """Main execution function"""
    # Initialize CKKS context
    print("Initializing CKKS encryption context...")
    ckks = CKKSContext()
    ckks.setup_context()
    
    # Save context for later use (fog nodes will need this)
    ckks.save_context()
    
    # Create encrypted smart meter
    meter = EncryptedSmartMeter(meter_id="METER_001", ckks_context=ckks)
    
    # Run continuously (60-second intervals)
    meter.run_continuous(interval_seconds=60)


if __name__ == "__main__":
    main()
