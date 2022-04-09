# CVE-2021-4034

Local privilege escalation via `pkexec`

## YouTube video

<p>
  <a href='https://www.youtube.com/watch?v=eTcVLqKpZJc'>
    <img src="https://user-images.githubusercontent.com/19750782/162562498-078f4bcb-4403-4ec4-acd4-b59530f081db.png" alt="PwnFunction YouTube Video" width="600">
  </a>
</p>

Watch the [✨ YouTube Video](https://www.youtube.com/watch?v=eTcVLqKpZJc)

## Run locally

```sh
make all && ./pwnkit && make clean
```

## Run in docker

```sh
# Build the docker image
docker build -t pwnkit .

# Run the exploit
docker run -it pwnkit bash
make all && ./pwnkit && make clean
```

## Detect using snyk-cli

```
snyk container test pwnkit:latest --file=Dockerfile
```

## Resources

- [Qualys Security Advisory](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)
- [argv silliness](https://ryiron.wordpress.com/2013/12/16/argv-silliness/)
