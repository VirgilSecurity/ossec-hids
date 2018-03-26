
stage("Get code"){
    node("master"){
        clearContentUnix()
        checkout scm
        stash includes: '**', excludes: "ci", name: "ossec-code"
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
    slaves["virgild-builder"] = createVirgildBuild("build-docker")
    parallel slaves
}

stage("Create Server Docker image"){
    node("build-docker"){
        ws {
            docker.image("centos:7").inside("--user root"){
                clearContentUnix()
            }
            sh 'mkdir ossec-server-artifact'
            dir('ossec-server-artifact'){
                unstash "ossec-server-artifact"
            }

            sh "mkdir virgild-artifact"
            dir("virgild-artifact"){
                unstash "virgild-artifact"
            }

            unstash "ossec-server-docker-files"
            unstash "ossec-ci-server"
            sh "mv ci/server/* ./"

            sh "docker build -t ossec-server ."
        }
    }
}

stage("Create Client Docker image"){
    node("build-docker"){

        docker.image("centos:7").inside("--user root"){
            clearContentUnix()
        }

        sh 'mkdir ossec-agent-artifact'
        dir('ossec-agent-artifact'){
            unstash "ossec-agent-artifact"
        }

        unstash "ossec-ci-client"
        sh "mv ci/client/* ./"

        sh "docker build -t ossec-client ."
    }
}


def createOssecServerBuild(slave){
    return {
        node(slave){
            ws {
                docker.image("centos:7").inside("--user root"){
                    clearContentUnix()
                }
                unstash "ossec-code"
                docker.image("centos:7").inside("--user root"){
                    
                    installDependencies()
                    installProtoC()
                    
                    sh "./install.sh"
                    sh "mkdir artifact"
                    sh "cp -r /var/ossec/* ./artifact/"

                }
                stash includes: 'artifact/**', name: "ossec-server-artifact"
            }
        }
    }
}

def createOssecClientBuild(slave){
    return {
        node(slave){
            ws {
                docker.image("centos:7").inside("--user root"){
                    clearContentUnix()
                }
                unstash "ossec-code"
                docker.image("centos:7").inside("--user root"){

                    installDependencies()
                    installProtoC()

                    sh "sed -i\'\' -e 's/USER_INSTALL_TYPE=\"server\"/USER_INSTALL_TYPE=\"agent\"/g' etc/preloaded-vars.conf"
                    sh "sed -i\'\' -e 's/#USER_AGENT_SERVER_NAME=\"ossec-server\"/USER_AGENT_SERVER_NAME=\"ossec-server\"/g' etc/preloaded-vars.conf"
                    sh "sed -i\'\' -e 's/#USER_AGENT_CONFIG_PROFILE=\"generic\"/USER_AGENT_CONFIG_PROFILE=\"generic\"/g' etc/preloaded-vars.conf"

                    sh "./install.sh"
                    sh "mkdir artifact"
                    sh "cp -r /var/ossec/* ./artifact/"
                }
                stash includes: 'artifact/**', name: "ossec-agent-artifact"
            }
        }
    }
}

def createVirgildBuild(slave){
    return {
        node(slave){
            ws {
                docker.image("centos:7").inside("--user root"){
                    clearContentUnix()
                }
                unstash "virgild-code"
                sh "sed -i\'\' -e 's/-it/-i/g' Makefile"
                sh "make build_in_docker-env"
                stash includes: 'virgild', name: "virgild-artifact"
            }
        }
    }
}

/// Utils

def clearContentUnix() {
    sh "rm -fr -- *"
}

def installDependencies(){
    sh "yum install -y epel-release"
    sh "yum install -y make"
    sh "yum install -y which bind-utils protoc nanopb python-protobuf libsodium unzip python-pip wget"
    sh "pip install --upgrade protobuf"
    sh "yum groupinstall -y 'Development Tools'"

    sh "wget http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm"
    sh "rpm -ivhy epel-release-latest-7.noarch.rpm"
    // clean after install
    sh "rm epel-release-latest-7.noarch.rpm"

    sh "yum install devtoolset-4-gcc*"
    sh "scl enable devtoolset-4 bash"
    sh "gcc --version"
}

def installProtoC () {
    sh "curl -OL https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip"
    sh "unzip protoc-3.2.0-linux-x86_64.zip -d protoc3"
    sh "mv protoc3/bin/* /usr/local/bin/"
    sh "mv protoc3/include/* /usr/local/include/"
    sh "chwon root /usr/local/bin/protoc"
    sh "chwon -R root /usr/local/include/google"
    // Clean after install
    sh "rm protoc-3.2.0-linux-x86_64.zip"
    sh "rm -r protoc3"
}