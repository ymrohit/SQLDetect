from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import joblib
import logging
'''
# Load your model
model_path = "best_model_SVM.pkl"
loaded_model = joblib.load(model_path)

app = FastAPI()

class Query(BaseModel):
    fields: dict

@app.post("/validate/")
async def validate_query(query: Query):
    # Iterate through each field to predict
    responses = {}
    for key, value in query.fields.items():
        if not isinstance(value, str):  # Ensure the value is a string
            continue
        # Predict using the loaded model
        prediction = loaded_model.predict([value])
        # Assuming 1 for SQL Injection and 0 for No Injection
        responses[key] = "SQL Injection Detected" if prediction[0] == 1 else "No Injection Detected"
    return {"results": responses}
'''
# Setup logging
logging.basicConfig(filename='sql_injection_logs.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Load your model
model_path = "best_model_SVM.pkl"
loaded_model = joblib.load(model_path)

app = FastAPI()

class Query(BaseModel):
    fields: dict

def detect_sql_injection(request: Request, data: dict):
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent')
    responses = {}
    for key, value in data.items():
        if not isinstance(value, str):  # Ensure the value is a string
            continue
        prediction = loaded_model.predict([value])
        if prediction[0] == 1:
            logging.info(f"SQL Injection Detected: IP={client_ip}, User-Agent={user_agent}, Field={key}, Value={value}")
            responses[key] = "SQL Injection Detected"
        else:
            responses[key] = "No Injection Detected"
    return responses

@app.post("/validate/")
async def validate_query(request: Request, query: Query):
    results = detect_sql_injection(request, query.fields)
    return {"results": results}

@app.get("/validate/")
async def validate_query_get(request: Request):
    # Convert query parameters to dictionary
    query_params = dict(request.query_params)
    results = detect_sql_injection(request, query_params)
    return {"results": results}

@app.get("/logs/")
async def view_logs():
    # Simple function to return logs (for demonstration; adjust as needed for production)
    with open('sql_injection_logs.log', 'r') as log_file:
        return {"logs": log_file.read()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
