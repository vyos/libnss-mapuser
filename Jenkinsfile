pipeline {
  agent none
  stages {
    stage('build-package') {
      parallel {
        stage('Build package amd64') {
          agent {
            docker {
              label 'jessie-amd64'
              args '--privileged --sysctl net.ipv6.conf.lo.disable_ipv6=0 -e GOSU_UID=1006 -e GOSU_GID=1006'
              image 'higebu/vyos-build:crux'
            }

          }
          steps {
            sh '''#!/bin/bash
git clone --single-branch --branch $GIT_BRANCH $GIT_URL $BUILD_NUMBER
cd $BUILD_NUMBER
sudo apt-get -o Acquire::Check-Valid-Until=false update
sudo mk-build-deps -i -r -t \'apt-get --no-install-recommends -yq\' debian/control
dpkg-buildpackage -b -us -uc -tc
mv ../*.deb .'''
          }
        }
        stage('Build package armhf') {
          agent {
            docker {
              label 'jessie-amd64'
              image 'vyos-build-armhf:crux'
              args '--privileged --sysctl net.ipv6.conf.lo.disable_ipv6=0 -e GOSU_UID=1006 -e GOSU_GID=1006'
            }

          }
          steps {
            sh '''#!/bin/bash
git clone --single-branch --branch $GIT_BRANCH $GIT_URL $BUILD_NUMBER
cd $BUILD_NUMBER
sudo apt-get -o Acquire::Check-Valid-Until=false update
sudo mk-build-deps -i -r -t \'apt-get --no-install-recommends -yq\' debian/control
dpkg-buildpackage -b -us -uc -tc
mv ../*.deb .'''
          }
        }
        stage('Build package arm64') {
          agent {
            docker {
              label 'jessie-amd64'
              args '--privileged --sysctl net.ipv6.conf.lo.disable_ipv6=0 -e GOSU_UID=1006 -e GOSU_GID=1006'
              image 'vyos-build-arm64:crux'
            }

          }
          steps {
            sh '''#!/bin/bash
git clone --single-branch --branch $GIT_BRANCH $GIT_URL $BUILD_NUMBER
cd $BUILD_NUMBER
sudo apt-get -o Acquire::Check-Valid-Until=false update
sudo mk-build-deps -i -r -t \'apt-get --no-install-recommends -yq\' debian/control
dpkg-buildpackage -b -us -uc -tc
mv ../*.deb .'''
          }
        }
      }
    }
    stage('Deploy package') {
      parallel {
        stage('Deploy package amd64') {
          agent {
            node {
              label 'jessie-amd64'
            }

          }
          steps {
            sh '''#!/bin/bash
cd $BUILD_NUMBER
mv *.deb ../
/var/lib/vyos-build/pkg-build.sh $GIT_BRANCH'''
          }
        }
        stage('Deploy package armhf') {
          agent {
            node {
              label 'jessie-amd64'
            }

          }
          steps {
            sh '''#!/bin/bash
cd $BUILD_NUMBER
mv *.deb ../
/var/lib/vyos-build/pkg-build.sh $GIT_BRANCH'''
          }
        }
        stage('Deploy package arm64') {
          agent {
            node {
              label 'jessie-amd64'
            }

          }
          steps {
            sh '''#!/bin/bash
cd $BUILD_NUMBER
mv *.deb ../
/var/lib/vyos-build/pkg-build.sh $GIT_BRANCH'''
          }
        }
      }
    }
    stage('Cleanup') {
      parallel {
        stage('Cleanup amd64') {
          agent {
            node {
              label 'jessie-amd64'
            }

          }
          steps {
            cleanWs()
          }
        }
        stage('Cleanup armhf') {
          agent {
            node {
              label 'jessie-amd64'
            }

          }
          steps {
            cleanWs()
          }
        }
        stage('Cleanup arm64') {
          agent {
            node {
              label 'jessie-amd64'
            }

          }
          steps {
            cleanWs()
          }
        }
      }
    }
  }
}

