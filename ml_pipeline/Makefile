.PHONY: all data train autoencoder finetune convert blocklist export clean

# Ensure we use the correct python (assumes venv_train is active or available)
PYTHON = python

all: data train autoencoder finetune convert blocklist export
	@echo "========================================"
	@echo "🚀 SafeLink ML Pipeline Complete!"
	@echo "Output models are in ml_pipeline/models/"
	@echo "Assets have been exported to Android app/src/main/assets/"
	@echo "========================================"

data:
	@echo "--> Running Data Collector..."
	$(PYTHON) data_collector.py

train:
	@echo "--> Running CNN+Dense Trainer..."
	$(PYTHON) trainer.py

autoencoder:
	@echo "--> Training Autoencoder..."
	$(PYTHON) autoencoder.py

finetune:
	@echo "--> Fine-tuning on False Positives..."
	$(PYTHON) finetune.py

convert:
	@echo "--> Converting Keras 3 to TFLite..."
	$(PYTHON) convert_tflite.py

blocklist:
	@echo "--> Building Static Blocklist..."
	$(PYTHON) build_blocklist.py

export:
	@echo "--> Exporting assets to Android..."
	$(PYTHON) export_assets.py

clean:
	@echo "--> Cleaning up generated models..."
	rm -rf models/*.keras models/*.tflite models/*.json models/*.onnx models/*.json
