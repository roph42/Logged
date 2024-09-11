pipeline {
  agent {
    dockerfile {
      filename 'Dockerfile'
    }

  }
  stages {
    stage('Build') {
      steps {
        sh '''

export FLASK_APP=app.py





























&& flask run'''
      }
    }

  }
}