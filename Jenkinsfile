CREDENTIALS_ID_SSH_GITHUB = 'avs-github-ssh'
CREDENTIALS_ID_S3_UPLOADER = 'aws-artifact-uploader'
CREDENTIALS_ID_GITHUB_TOKEN = 'github-repo-access'
AWS_ROOT_URL = 'https://s3-eu-west-1.amazonaws.com'
ASSETS_BUCKET_PREFIX = 'public.wire.com/artifacts'

buildNumber = currentBuild.id
version = null
branchName = null
commitId = null
repoName = null

pipeline {
    agent { label 'linuxbuild' }

    options {
        disableConcurrentBuilds()
    }

    // NOTE: checks every 5 minutes if a new commit occurred after last successful run
    triggers {
        pollSCM 'H/5 * * * *'
    }

    stages {
        stage( 'Checkout' ) {
            steps {
                script {
                    def vcs = checkout([
                        $class: 'GitSCM',
                        changelog: true,
                        userRemoteConfigs: scm.userRemoteConfigs,
                        branches: scm.branches,
                        extensions: scm.extensions + [
                            [
                            $class: 'SubmoduleOption',
                            disableSubmodules: false,
                            recursiveSubmodules: true,
                            parentCredentials: true
                            ],
                            [
                                $class: 'WipeWorkspace'
                            ]
                        ]
		            ])
                    branchName = vcs.GIT_BRANCH.tokenize( '/' ).drop( 1 ).join( '/' )
                    commitId = "${vcs.GIT_COMMIT}"[0..6]
                    repoName = vcs.GIT_URL.tokenize( '/' ).last().tokenize( '.' ).first()
                    repoUser = vcs.GIT_URL.tokenize( '/' )[-2]

                    release_version = branchName.replaceAll("[^\\d\\.]", "");
                    if (release_version.length() > 0 || branchName.contains('release')) {
                        version = release_version + "." + buildNumber
                    } else {
                        version = "0.0.${buildNumber}"
                    }
                }
            }
        }

        stage('Build') {
            agent {
                dockerfile true
            }
            steps {
                echo '### Obtaining build information'
                script {
                    platform = sh(
                        returnStdout: true,
                        script: """
                            #!/usr/bin/env bash

                            make dump \
                                | grep TARGET_ARCH \
                                | awk -F "=" '{print \$2}'
                        """
                    ).trim()
                }
                sh """
                    cp /build/sftd/sftd ./wire-sftd
                    mkdir upload
                    cd upload
                    tar -zcvf wire-sft-${ version }-${ platform }-amd64.tar.gz ./../wire-sftd
                    openssl dgst -sha256 wire-sft-${ version }-${ platform }-amd64.tar.gz | awk '{ print \$2 }' > wire-sft-${ version }-${ platform }-amd64.sha256
                    # COMPAT: using one file for potentially multiple checksums is deprecated
                    openssl dgst -sha256 wire-sft-${ version }-${ platform }-amd64.tar.gz | awk '{ print "sha256:"\$2 }' > wire-sft-${ version }-${ platform }-amd64.sum

                    cp /build/sftd/sftd $WORKSPACE
                    cp upload/wire-sft-* $WORKSPACE
                """
                archiveArtifacts artifacts: "sftd,wire-sft-*"
            }
        }

        stage( 'Build container' ) {
            steps {
                mapping: ['sftd' : 'sftd']
                sh(
                    script: """
                        buildah bud \
                            --file "${ env.WORKSPACE }/jenkins/containers/Containerfile.sftd" \
                            --squash \
                            --no-cache \
                            --tag sftd:${ version } \
                            ./
                    """
                )
            }
        }

        stage( 'Uploading new artifact' ) {
            when {
                anyOf {
                    expression { return "${ branchName }".startsWith( 'release' ) }
                }
            }

            environment {
                // NOTE: adjust to allow precedence introduces by 'venv'
                PATH = "${ env.WORKSPACE }/.venv/bin:${ env.PATH }"
            }

            steps {
                echo '### Creating a new local Python environment and installing dependencies'

                sh(
                    script: """
                        #!/usr/bin/env bash

                        cd "${ env.WORKSPACE }"

                        rm -rf ./.venv
                        python3 -m venv .venv

                        pip3 install --upgrade pip
                        pip3 install wheel

                        pip3 install -r ./jenkins/ansible/sft/requirements.txt
                    """
                )

                echo '### Uploading assets to s3'

                withCredentials([ usernamePassword( credentialsId: CREDENTIALS_ID_S3_UPLOADER, usernameVariable: 'keyId', passwordVariable: 'accessKey' ) ]) {
                    sh(
                        script: """
                            #!/usr/bin/env bash

                            AWS_ACCESS_KEY_ID=${ keyId } \
                            AWS_SECRET_ACCESS_KEY=${ accessKey } \
                            AWS_DEFAULT_REGION=eu-west-1 \
                            aws s3 cp \
                                ./upload/ \
                                s3://${ ASSETS_BUCKET_PREFIX }/ \
                                --recursive \
                                --include "wire-sft-${ version }-${ platform }-amd64.*"
                        """
                    )
                }
            }
        }

        stage( 'Releasing new version' ) {
            when {
                expression { return "${ branchName }".startsWith( 'release' ) }
            }

            environment {
                // NOTE: adjust to allow precedence introduces by 'venv'
                PATH = "${ env.WORKSPACE }/.venv/bin:${ env.PATH }"
            }

            steps {
                echo '### Creating a new local Python environment and installing dependencies'

                sh(
                    script: """
                        #!/usr/bin/env bash

                        cd "${ env.WORKSPACE }"

                        rm -rf ./.venv
                        python3 -m venv .venv

                        pip3 install --upgrade pip
                        pip3 install wheel

                        pip3 install -r ./jenkins/ansible/sft/requirements.txt
                    """
                )

                echo '### Pushing container image to registry'

                withCredentials([ file( credentialsId: CREDENTIALS_ID_IMAGE_REGISTRY, variable: 'authJsonPath' ) ]) {
                    sh(
                        script: """
                            #!/usr/bin/env bash

                            cd "${ env.WORKSPACE }"

                            buildah push \
                                --authfile ${ authJsonPath } \
                                sftd:${ version } \
                                quay.io/wire/sftd:${ version }
                        """
                    )
                }

                echo "### Tagging as ${ version }"

                withCredentials([ sshUserPrivateKey( credentialsId: CREDENTIALS_ID_SSH_GITHUB, keyFileVariable: 'sshPrivateKeyPath' ) ]) {
                    sh(
                        script: """
                            #!/usr/bin/env bash

                            git tag ${ version }

                            git \
                                -c core.sshCommand='ssh -i ${ sshPrivateKeyPath }' \
                                push \
                                origin ${ version }
                        """
                    )
                }

                echo '### Creating release on Github'

                withCredentials([ string( credentialsId: CREDENTIALS_ID_GITHUB_TOKEN, variable: 'accessToken' ) ]) {
                    sh(
                        script: """
                            #!/usr/bin/env bash

                            cd "${ env.WORKSPACE }"

                            GITHUB_USER=${ repoUser } \
                            GITHUB_TOKEN=${ accessToken } \
                            python3 ./jenkins/release-on-github.py \
                                ${ repoName } \
                                ./upload \
                                ${ version } \
                                ${ AWS_ROOT_URL }/${ ASSETS_BUCKET_PREFIX }
                        """
                    )
                }
            }
        }
    }

    post {
        success {
            node( 'built-in' ) {
                withCredentials([ string( credentialsId: 'wire-jenkinsbot', variable: 'jenkinsbot_secret' ) ]) {
                    wireSend secret: "$jenkinsbot_secret", message: "✅ ${JOB_NAME} #${ BUILD_ID } succeeded\n${ BUILD_URL }console\nhttps://github.com/wireapp/wire-avs-service/commit/${ commitId }"
                }
            }
        }

        failure {
            node( 'built-in' ) {
                withCredentials([ string( credentialsId: 'wire-jenkinsbot', variable: 'jenkinsbot_secret' ) ]) {
                    wireSend secret: "$jenkinsbot_secret", message: "❌ ${JOB_NAME} #${ BUILD_ID } failed\n${ BUILD_URL }console\nhttps://github.com/wireapp/wire-avs-service/commit/${ commitId }"
                }
            }
        }
    }
}
