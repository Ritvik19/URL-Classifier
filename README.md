# URL Classifier

**Classification of URLs as Malicious or Benign**

This Repo consists of the following notebooks:

* Web Metrics Scrapper : Scrapes dataset for the project
* Data and Features : Additional Feature generation and their explaination
* TestDataPrep : Preparation of test dataset for model perforamnce evaluation
* Model Fitting : Model Fitting on Training Data and performance evaluation on the test data

Libraires used:

* sci-kit learn
```
pip install sklearn
```
* keras
```
pip install keras
```

There are the following models in this repo:

* LR.pickle : Logistic Regression Classfier
* RFC.pickle : Random Forest Classifier
* Scaler.pickle : Standard Scaler for preprocessing required for Neural Network
* model.h5 : Artificial Neural Network Classfier