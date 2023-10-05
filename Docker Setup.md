# Docker

# Setting up Web Challenge using Docker

Be in the folder where the Dockerfile exists

```bash
┌──(kali㉿kali)-[~/ctf/WebCTF]
└─$ ls         
challenge  distfiles  docker-compose.yml  Dockerfile  solution

(sample output)
```

Now run the following command using sudo privileges:

```bash
┌──(kali㉿kali)-[~/ctf/WebCTF]
└─$ docker build -t www-data/chall1 .
```

- **`docker build`**: This part of the command instructs Docker to build a new Docker image.
- **`t www-data/chall1`**: The **`t`** flag is used to specify a name and optionally a tag to the Docker image being built. In this case, the image is being tagged with the name **`www-data/chall1`**. A tag in Docker is a label assigned to a specific image version. It's useful for versioning and managing different variations of the same base image.
- where `chall1` is a sample unique name for every challenge you might want to build.
- **`.`**: The dot (**`.`**) at the end of the command represents the build context. The build context is the set of files located in the current directory and its subdirectories. These files are sent to the Docker daemon to be used in the build process. In other words, Docker will look for a Dockerfile in the current directory (and its subdirectories) to build the image.

Now use the following command which is explained below

```bash
┌──(kali㉿kali)-[~/ctf/WebCTF]
└─$ sudo docker run –d –p 8080:8080 www-data/chall1
```

- **`sudo`**: This command is used in Unix-like operating systems to allow a permitted user to execute a command as the superuser or another user, as specified in the security policy configured in the **`sudoers`** file. It's often required for running Docker commands, especially if you're not the root user.
- **`docker run`**: This part of the command is used to run a new Docker container based on a specified image.
- **`d`**: This flag stands for "detached" mode. When you run a container in detached mode (**`d`**), it means the container will run in the background without blocking your terminal. You'll get the command prompt back immediately after executing the Docker run command.
- **`p 8080:8080`**: This flag is used to publish a container's port to the host. In this case, it maps port 8080 on the host to port 8080 on the container. This means that you can access the services inside the container, which are running on port 8080, from your host machine by connecting to port 8080.
- **`www-data/chall1`**: This specifies the name of the Docker image from which the container will be created.

After running the command **`sudo docker run -d -p 8080:8080 www-data/chall1`**, several things happen:

1. **Docker Image Check**: Docker checks if the **`www-data/chall1`** image exists locally. If the image does not exist, Docker will attempt to pull it from a Docker registry (like Docker Hub) before creating the container.
2. **Container Creation**: Docker creates a new container based on the specified image (**`www-data/chall1`**). This container is an instance of the image, isolated from the host system and other containers.
3. **Detached Mode**: Because of the **`d`** flag, the container runs in detached mode. This means it runs in the background, allowing you to continue using your terminal for other commands without being attached to the container's console.
4. **Port Mapping**: The **`p 8080:8080`** flag maps port 8080 on the host machine to port 8080 in the container. This enables you to access services inside the container via **`localhost:8080`** on your host machine.
5. **Background Execution**: The container starts running in the background, and you receive a unique container ID as output. This ID can be used to manage the container later.
6. **Container Management**: You can use various Docker commands to manage the running container. For example, you can stop the container using **`docker stop <container_id>`**, remove it using **`docker rm <container_id>`**, or inspect its logs using **`docker logs <container_id>`**.
7. **Service Access**: If the application inside the container provides a service (like a web server), you can access that service by visiting **`http://localhost:8080`** in your web browser or by making HTTP requests to **`localhost:8080`** using tools like **`curl`** or web browsers. The requests will be routed to the application running inside the container on port 8080.