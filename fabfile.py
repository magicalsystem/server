from fabric.api import run, cd

def deploy():
    with cd("~/server"):
        run("git pull")
        run("supervisorctl restart app")

