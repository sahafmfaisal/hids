"""HIDS ML Trainer — called once by install.sh"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

FEATURES = ["open_count","read_count","write_count","exec_count",
            "delete_count","chmod_count","privilege_used","bulk_operation"]
BASE     = os.path.dirname(__file__)
MODEL    = os.path.join(BASE, "model.pkl")
META     = os.path.join(BASE, "model_meta.json")

np.random.seed(42)

def normal(n=700):
    return pd.DataFrame({
        "open_count":    np.random.randint(0,15,n),
        "read_count":    np.random.randint(0,30,n),
        "write_count":   np.random.randint(0,10,n),
        "exec_count":    np.random.randint(0,3,n),
        "delete_count":  np.random.randint(0,2,n),
        "chmod_count":   np.zeros(n,int),
        "privilege_used":np.zeros(n,int),
        "bulk_operation":np.zeros(n,int),
        "label": 0
    })

def attacks(n=100):
    rows=[]
    for _ in range(n):
        rows += [
            {"open_count":np.random.randint(30,55),"read_count":np.random.randint(80,130),
             "write_count":0,"exec_count":np.random.randint(2,6),"delete_count":0,
             "chmod_count":0,"privilege_used":0,"bulk_operation":1,"label":1},
            {"open_count":np.random.randint(35,55),"read_count":np.random.randint(70,110),
             "write_count":0,"exec_count":np.random.randint(2,5),"delete_count":0,
             "chmod_count":0,"privilege_used":1,"bulk_operation":1,"label":1},
            {"open_count":np.random.randint(50,70),"read_count":np.random.randint(200,280),
             "write_count":np.random.randint(250,360),"exec_count":np.random.randint(4,8),
             "delete_count":np.random.randint(40,60),"chmod_count":0,
             "privilege_used":0,"bulk_operation":1,"label":1},
            {"open_count":np.random.randint(20,40),"read_count":np.random.randint(60,100),
             "write_count":np.random.randint(50,90),"exec_count":np.random.randint(6,10),
             "delete_count":0,"chmod_count":0,"privilege_used":0,"bulk_operation":1,"label":1},
            {"open_count":np.random.randint(10,25),"read_count":np.random.randint(40,75),
             "write_count":np.random.randint(0,8),"exec_count":np.random.randint(1,3),
             "delete_count":np.random.randint(1,4),"chmod_count":np.random.randint(1,3),
             "privilege_used":0,"bulk_operation":0,"label":1},
        ]
    return pd.DataFrame(rows)

df = pd.concat([normal(), attacks()], ignore_index=True).sample(frac=1,random_state=42)
X,y = df[FEATURES], df["label"]
Xt,Xv,yt,yv = train_test_split(X,y,test_size=.2,stratify=y,random_state=42)

pipe = Pipeline([
    ("sc", StandardScaler()),
    ("clf", VotingClassifier([
        ("rf",  RandomForestClassifier(n_estimators=150,max_depth=9,random_state=42)),
        ("svm", SVC(kernel="rbf",C=2.0,gamma="scale",probability=True,random_state=42)),
    ], voting="soft"))
])
pipe.fit(Xt,yt)
report = classification_report(yv, pipe.predict(Xv), output_dict=True)
joblib.dump(pipe, MODEL)
with open(META,"w") as f:
    json.dump({"model":"RF+SVM Ensemble","features":FEATURES,
               "accuracy":round(report["accuracy"],4),"samples":len(df)}, f, indent=2)
print(f"✓ Model trained  accuracy={report['accuracy']*100:.1f}%  saved={MODEL}")
