from fabric.api import run, cd, prefix

def deploy():
    with cd("~/server"):
        run("git pull")
        with prefix("source ./env/bin/activate"):
            run("pip install -r requirements.txt")
        run("supervisorctl restart app")
    with cd("~/docs"):
        run("git pull")
        run("make html")
