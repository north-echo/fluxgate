pipeline {
    agent any

    stages {
        stage('Label PR') {
            when {
                changeRequest()
            }
            steps {
                sh "echo Building branch ${env.CHANGE_BRANCH}"
                sh "echo PR title: ${env.CHANGE_TITLE}"
            }
        }
    }
}
