pipeline {
    agent any

    stages {
        stage('Validate PR') {
            when {
                changeRequest()
            }
            environment {
                DEPLOY_TOKEN = credentials('deploy-token')
                NPM_TOKEN = credentials('npm-auth-token')
            }
            steps {
                sh 'npm ci'
                sh 'npm test'
            }
        }
    }
}
