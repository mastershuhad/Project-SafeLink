@echo off
echo ========================================
echo SafeLink ML Pipeline
echo ========================================

echo.
echo --^> Running Data Collector...
python data_collector.py
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo --^> Running CNN+Dense Trainer...
python trainer.py
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo --^> Training Autoencoder...
python autoencoder.py
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo --^> Fine-tuning on False Positives...
python finetune.py
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo --^> Converting Keras 3 to TFLite...
python convert_tflite.py
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo --^> Building Static Blocklist...
python build_blocklist.py
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo --^> Exporting assets to Android...
python export_assets.py
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo ========================================
echo 🚀 SafeLink ML Pipeline Complete!
echo Output models are in ml_pipeline\models\
echo Assets have been exported to Android app\src\main\assets\
echo ========================================
