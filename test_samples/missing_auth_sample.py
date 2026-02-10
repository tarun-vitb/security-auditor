# Missing authentication sample
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

# No authentication on sensitive endpoints
@app.post("/admin/delete_user")
def delete_user(user_id: int):
    # Dangerous: No auth check
    return {"deleted": user_id}

@app.post("/api/update_password")
def update_password(user_id: int, new_password: str):
    # Missing auth middleware
    return {"status": "updated"}

@app.delete("/users/{user_id}")
def remove_user(user_id: int):
    # DELETE endpoint without authentication
    return {"removed": user_id}

@app.put("/settings/admin")
def update_admin_settings(settings: dict):
    # Sensitive operation without auth
    return {"settings": settings}
