CREDENTIALS_ID_IMAGE_REGISTRY = 'quayio-image-push'
CREDENTIALS_ID_SSH_GITHUB = 'avs-github-ssh'
CREDENTIALS_ID_S3_UPLOADER = 'aws-artifact-uploader'
CREDENTIALS_ID_GITHUB_TOKEN = 'github-repo-access'
AWS_ROOT_URL = 'https://s3-eu-west-1.amazonaws.com'
ASSETS_BUCKET_PREFIX = 'public.wire.com/artifacts'
HELM_REPO = "s3://public.wire.com/charts-avs"
HELM_REPO_HTTPS = "https://s3-eu-west-1.amazonaws.com/public.wire.com/charts-avs"

def buildNumber = currentBuild.id
def branchName = null
def version = null
def commitId = null
def repoName = null

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
        stage('Get tags') {
            steps {
                script {
                    tags_res = sh(script: "git tag --contains HEAD", returnStdout: true).trim()

                    echo "tags"
                    echo tags_res

                    tags = tags_res.split('\n')
                    env.IS_MAIN_RELEASE = "0"
                    if (tags.any{ it.startsWith("stefan-") }) {
                        env.IS_MAIN_RELEASE = "1"
                    }
                }
            }

        }

        stage('Build') {
            agent {
                dockerfile true
            }

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
                            parentCredentials: true,
                            noTags: false
                            ],
                            [
                                $class: 'WipeWorkspace'
                            ]
                        ]
		            ])
                    branchName = vcs.GIT_BRANCH
                    commitId = "${vcs.GIT_COMMIT}"[0..6]
                    repoName = vcs.GIT_URL.tokenize( '/' ).last().tokenize( '.' ).first()


                    release_version = branchName.replaceAll("[^\\d\\.]", "");
                    if (release_version.length() > 0 || branchName.contains('release')) {
                        version = release_version + "." + buildNumber
                    } else {
                        version = "0.0.${buildNumber}"
                    }
                }
            }
        }

        stage("Test") {
            steps {
                sh '''
                echo IS_MAIN_RELEASE $IS_MAIN_RELEASE
                echo meh
                '''
            }
        }

    }
}

