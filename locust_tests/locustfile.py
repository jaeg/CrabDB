from locust import HttpUser, TaskSet, task, between
import json

class UserTasks(TaskSet):
  @task
  def on_start(self):
    # Send login request
    response = self.client.post("/auth", auth=("user", "password"))

    # set "token" from response header
    self.client.headers.update({'Authorization': response.headers.get('token')})

  @task
  def wholeDB(self):
    response = self.client.get("/db/1")

  @task
  def addData(self):
    response = self.client.put("/db/1",data=json.dumps({
        "data":"test"
        }))


class WebsiteUser(HttpUser):
    host = "http://127.0.0.1:8090"
    wait_time = between(2, 5)
    tasks = [UserTasks]