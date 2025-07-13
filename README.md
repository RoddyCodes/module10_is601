# Module 10 - IS601 Project

This repository contains the solution for Module 10 of the IS601 course. It includes a Python application with its dependencies managed via `requirements.txt`, local tests with `pytest`, and a Docker Compose setup for containerization.

## Table of Contents

- [Local Development Setup & Running Tests](#local-development-setup--running-tests)
- [Running with Docker Compose](#running-with-docker-compose)
- [Docker Hub Repository](#docker-hub-repository)

---

## Local Development Setup & Running Tests

Follow these steps to set up the project locally and run the tests:

1.  **Clone the Repository:**
    First, clone this repository to your local machine:

    ```bash
    git clone [https://github.com/RoddyCodes/module10_is601.git](https://github.com/RoddyCodes/module10_is601.git)
    ```

2.  **Navigate to the Project Directory:**
    Change into the cloned repository's directory:

    ```bash
    cd module10_is601
    ```

3.  **Create a Virtual Environment:**
    It's highly recommended to use a Python virtual environment to manage project dependencies.

    ```bash
    python3 -m venv .venv
    ```

4.  **Activate the Virtual Environment:**
    Activate the virtual environment you just created.

    - **macOS/Linux:**
      ```bash
      source .venv/bin/activate
      ```
    - **Windows (Command Prompt):**
      ```cmd
      .venv\Scripts\activate.bat
      ```
    - **Windows (PowerShell):**
      `powershell
    .venv\Scripts\Activate.ps1
    `
      Your terminal prompt should now show `(.venv)` to indicate the environment is active.

5.  **Install Dependencies:**
    Install all required Python packages using `pip` and the `requirements.txt` file:

    ```bash
    pip install -r requirements.txt
    ```

6.  **Run Local Tests:**
    Once dependencies are installed, you can run the project's tests using `pytest`:

    ```bash
    pytest
    ```

    This command will execute all discovered tests in your project.

7.  **Deactivate the Virtual Environment (When Done):**
    When you're finished working on the project, you can deactivate the virtual environment:
    ```bash
    deactivate
    ```

---

## Running with Docker Compose

This project includes Docker Compose files to easily set up and run the application and its services (e.g., database) in isolated containers.

1.  **Ensure Docker is Running:**
    Make sure Docker Desktop (or your Docker daemon) is running on your machine.

2.  **Navigate to the Project Directory:**
    Ensure your terminal is in the root directory of the project (where `docker-compose.yml` is located).

3.  **Build and Run the Application:**
    Use `docker compose up` with the `--build` flag to build the necessary images and start all services defined in `docker-compose.yml`. The `-d` flag runs them in detached (background) mode.

    ```bash
    docker compose up --build -d
    ```

    This command will:

    - Build the application's Docker image (if changes detected or forced).
    - Create and start all services (e.g., your web app, database, etc.).
    - Set up necessary networks and volumes.

4.  **Check Service Status and Logs (Optional):**
    To see the status of your running containers:

    ```bash
    docker compose ps
    ```

    To view the logs from all services (useful for debugging):

    ```bash
    docker compose logs -f
    ```

5.  **Stop and Clean Up (When Done):**
    When you are finished using the Dockerized application, it's good practice to stop and remove the containers, networks, and (optionally) volumes:
    ```bash
    docker compose down
    ```
    _To also remove volumes (which might contain database data - use with caution!):_
    ```bash
    docker compose down -v
    ```

---

## Docker Hub Repository

The Docker image for this project is also available on Docker Hub:

[**RoddyCodes / is601_module10**](https://hub.docker.com/repository/docker/roddycodes/is601_module10/general)

You can pull the image directly (if it's public) using:

```bash
docker pull roddycodes/is601_module10:latest
```
