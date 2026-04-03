@Library('shared-pipeline-lib') _

pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
    }
}
