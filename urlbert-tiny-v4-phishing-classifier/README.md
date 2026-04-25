---
datasets:
- ealvaradob/phishing-dataset
language:
- en
base_model:
- CrabInHoney/urlbert-tiny-base-v4
pipeline_tag: text-classification
tags:
- url
- urls
- links
- classification
- tiny
- phishing
- urlbert
license: apache-2.0
new_version: CrabInHoney/urlbert-tiny-v5
---
This is a very small version of BERT, designed to categorize links into phishing and non-phishing links

An updated, lighter version of the old classification model for URL analysis

Old version: https://huggingface.co/CrabInHoney/urlbert-tiny-v3-phishing-classifier
##### Comparison with the previous version of urlbert phishing-classifier:

| Version  | Accuracy  | Precision  | Recall  |  F1-score |
| ------------ | ------------ | ------------ | ------------ | ------------ |
|  v2 |  0.9665 |  0.9756 |  0.9522 | 0.9637  |
| v3 | 0.9819  |  0.9876 | 0.9734  | 0.9805|
| **v4 (this model)** | **0.9907**  |  **0.9945** | **0.9855**  | **0.9900** |

Model size

3.69M params

Tensor type

F32

[Dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset "Dataset")
(urls.json only)

Example:



    from transformers import BertTokenizerFast, BertForSequenceClassification, pipeline
    import torch
    
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Используемое устройство: {device}")
    
    model_name = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
    
    tokenizer = BertTokenizerFast.from_pretrained(model_name)
    model = BertForSequenceClassification.from_pretrained(model_name)
    model.to(device)
    
    classifier = pipeline(
        "text-classification",
        model=model,
        tokenizer=tokenizer,
        device=0 if torch.cuda.is_available() else -1,
        return_all_scores=True
    )
    
    test_urls = [
        "huggingface.co/",
        "hu991ngface.com.ru/"
    ]
    
    label_mapping = {"LABEL_0": "good", "LABEL_1": "fish"}
    
    for url in test_urls:
        results = classifier(url)
        print(f"\nURL: {url}")
        for result in results[0]: 
            label = result['label']
            score = result['score']
            friendly_label = label_mapping.get(label, label)
            print(f"Класс: {friendly_label}, вероятность: {score:.4f}")


Используемое устройство: cuda

URL: huggingface.co/
Класс: good, вероятность: 0.9710
Класс: fish, вероятность: 0.0290

URL: hu991ngface.com.ru/
Класс: good, вероятность: 0.0013
Класс: fish, вероятность: 0.9987