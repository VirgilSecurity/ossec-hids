
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
    createOssecServerBuild("build-docker")
    createOssecClientBuild("build-docker")
    createVirgildBuild("build-docker")
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

stage("Publish images"){
    node("build-docker"){
        echo env.BRANCH_NAME
        def BRANCH_NAME = env.BRANCH_NAME
        
        withCredentials([string(credentialsId: 'REGISTRY_PASSWORD', variable: 'REGISTRY_PASSWORD'), string(credentialsId: 'REGISTRY_USER', variable: 'REGISTRY_USERNAME')]) {
            sh "docker tag ossec-server virgilsecurity/ossec-server:${BRANCH_NAME}"
            sh "docker tag ossec-client virgilsecurity/ossec-client:${BRANCH_NAME}"
            sh "docker login -u ${REGISTRY_USERNAME} -p ${REGISTRY_PASSWORD} && docker push virgilsecurity/ossec-server:${BRANCH_NAME} && docker push virgilsecurity/ossec-client:${BRANCH_NAME}"
        }
    }
}

def createOssecServerBuild(slave){
    node(slave){
        ws {
            docker.image("centos:7").inside("--user root"){
                clearContentUnix()
            }
            unstash "ossec-code"
            docker.image("centos:7").inside("--user root"){
                
                installDependencies()
                installProtoC()
                
                useV4DevToolSet("./install.sh")
                sh "mkdir artifact"
                sh "mv /var/ossec/* ./artifact/"

            }
            stash includes: 'artifact/**', name: "ossec-server-artifact"
        }
    }
}

def createOssecClientBuild(slave){
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

                useV4DevToolSet("./install.sh")
                sh "mkdir artifact"
                sh "mv /var/ossec/* ./artifact/"
            }
            stash includes: 'artifact/**', name: "ossec-agent-artifact"
        }
    }
}

def createVirgildBuild(slave){
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

/// Utils

def clearContentUnix() {
    sh "rm -fr -- *"
}

def installDependencies(){
    sh "yum install -y epel-release"
    sh "yum install -y centos-release-scl"
    sh "yum install -y make which bind-utils protoc nanopb python-protobuf libsodium libsodium-devel libuv-static unzip python-pip wget libcurl libcurl-devel libuv-devel zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel expat-devel libasan"
    sh "pip install --upgrade protobuf"
    sh "yum groupinstall -y 'Development Tools'"

    sh "yum install -y devtoolset-4-gcc* devtoolset-4-libasan-devel"
    
    // Install cmake
    sh "wget https://cmake.org/files/v3.10/cmake-3.10.3-Linux-x86_64.sh"
    sh "mkdir /opt/cmake"
    sh "chmod +x ./cmake-3.10.3-Linux-x86_64.sh && ./cmake-3.10.3-Linux-x86_64.sh --prefix=/opt/cmake --skip-license && rm -f ./cmake-3.10.3-Linux-x86_64.sh"
    sh "ln -s /opt/cmake/bin/cmake /usr/bin/cmake"
    sh "cmake -version"

    useV4DevToolSet("gcc --version")
}

def useV4DevToolSet(command){
    sh "scl enable devtoolset-4 \"$command\""
}

def installProtoC(){
    sh "curl -OL https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip"
    sh "unzip protoc-3.2.0-linux-x86_64.zip -d protoc3"
    sh "mv protoc3/bin/* /usr/local/bin/"
    sh "mv protoc3/include/* /usr/local/include/"
    sh "chown root /usr/local/bin/protoc"
    sh "chown -R root /usr/local/include/google"
    // Clean after install
    sh "rm protoc-3.2.0-linux-x86_64.zip"
    sh "rm -r protoc3"
}