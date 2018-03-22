
stage("Get code"){
    node("master"){
        clearContentUnix()
        checkout scm
        stash includes: '**', excludes: "ci" name: "ossec-code"
        stash includes: 'ci/server/**', name: "ossec-ci-server"
        stash includes: 'ci/client/**', name: "ossec-ci-client"

        clearContentUnix()
        git branch: "no-auth", url: 'https://github.com/VirgilSecurity/virgild.git'
        stash includes: '**', name: "virgild-code"
        
        clearContentUnix()
        git 'https://github.com/ossec/ossec-docker.git'
        stash includes: '**', excludes: 'Dockerfile, ossec-server.sh', name: "ossec-server-docker-files"

        clearContentUnix()
    }
}

stage("Build"){
    def slaves = [:]
    slaves["ossec-server-builder"] = createOssecServerBuild("build-docker")
    slaves["ossec-client-builder"] = createOssecClientBuild("build-docker")
    // slaves["virgild-builder"] = createVirgildBuild()
    slaves paralell
}

stage("Create Server Docker image"){
    node("build-docker"){

        clearContentUnix()

        sh 'mkdir ossec-artifact'
        dir('ossec-artifact'){
            unstash "ossec-server-artifact"
        }
        
        sh "mkdir virgild-artifact"
        dir("virgild-artifact"){
            unstash "virgild-artifact"
        }

        unstash "ossec-server-docker-files"
        unstash "ossec-ci-server"

        // here must be docker build
    }
}

stage("Create Client Docker image"){
    node("build-docker"){

        clearContentUnix()

        sh 'mkdir ossec-artifact'
        dir('ossec-artifact'){
            unstash "ossec-client-artifact"
        }

        unstash "ossec-server-docker-files"
        unstash "ossec-ci-client"

        // here must be docker build
    }
}


def createOssecServerBuild(slave){
    return {
        node(slave){
            docker.image("centos:7").inside("--user root"){
                sh "yum install -y epel-release"
                sh "yum install -y make"
                sh "yum groupinstall -y 'Development Tools'"
                sh "./install.sh"
                sh "cp -r /var/ossec ./artifact"
            }
            stash includes: 'artifact/**', name: "ossec-server-artifact"
            clearContentUnix("artifact")
        }
    }
}

def createOssecClientBuild(slave){
    return {
        node(slave){
            docker.image("centos:7").inside("--user root"){
                sh "yum install -y epel-release"
                sh "yum install -y make"
                sh "yum groupinstall -y 'Development Tools'"
                sh "sed 's/USER_INSTALL_TYPE=\"server\"/USER_INSTALL_TYPE=\"client\"/g'"
                sh "./install.sh"
                sh "cp -r /var/ossec ./artifact"
            }
            stash includes: 'artifact/**', name: "ossec-client-artifact"
            clearContentUnix("artifact")
        }
    }
}

def createVirgildBuild(slave){
    return {
        node(slave){
            make buil_in_docker-env
        }
    }
}

/// Utils

def clearContentUnix() {
    sh "rm -fr -- *"
}