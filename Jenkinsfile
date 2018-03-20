
stage("Get code"){
    node("master"){
        clearContentUnix()
        checkout scm
        stash includes: '**', name: "ossec-code"

        clearContentUnix()
        git 'https://github.com/VirgilSecurity/virgild.git'
        stash includes: '**', name: "virgild-code"
    }
}

stage("Build"){
    def slaves = [:]
    slaves["ossec-builder"] = createOssecBuild("build-docker")
    // slaves["virgild-builder"] = createVirgildBuild()
    slaves paralell
}

stage("Create Docker image"){
    node("build-docker"){
        
    }
}

def createOssecBuild(slave){
    return {
        node(slave){
            docker.image("centos:7").inside("--user root"){
                sh "yum install -y epel-release"
                sh "yum install -y make"
                sh "yum groupinstall -y 'Development Tools'"
                sh "./install.sh"
                sh "cp -r /var/ossec ./artifact"
            }
            stash includes: 'artifact/**', name: "ossec-artifat"
        }
    }
}

def createVirgildBuild(slave){
    return {
        node(slave){
            docker.image("centos:7").inside("--user root"){

            }
        }
    }
}

/// Utils

def clearContentUnix() {
    sh "rm -fr -- *"
}