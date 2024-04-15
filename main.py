from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import joblib
import logging
from fastapi.middleware.cors import CORSMiddleware
logging.basicConfig(filename='sql_injection_logs.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Load your model
model_path = "best_model_SVM_V2.pkl"
loaded_model = joblib.load(model_path)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"]   # Allows all headers
)
class Query(BaseModel):
    fields: dict
SAFE_WORDS = {"admin", "user"}
def detect_sql_injection(request: Request, data: dict):
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent')
    responses = {}
    for key, value in data.items():
        if not isinstance(value, str):  # Ensure the value is a string
            continue
        #print(f"Checking field {key} with value '{value}'")
        if value.strip().lower()  in SAFE_WORDS:
            responses[key] = "No Injection Detected"
            continue
        prediction = loaded_model.predict([value])
        if prediction[0] == 1:
            logging.info(
                    f"SQL Injection Detected: IP={client_ip}, User-Agent={user_agent}, Field={key}, Value={value}")
            responses[key] = "SQL Injection Detected"
        else:
            responses[key] = "No Injection Detected"
    return responses

@app.post("/validate/")
async def validate_query(request: Request, query: Query):
    results = detect_sql_injection(request, query.fields)
    print(query.fields)
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
