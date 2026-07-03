pipeline {
    agent any

    stages {
        stage('Label PR') {
            when {
                changeRequest()
            }
            steps {
                sh "echo Building branch ${env.CHANGE_BRANCH}"
                sh "git checkout ${env.CHANGE_BRANCH}"
            }
        }
    }
}
