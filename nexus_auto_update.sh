GITHUB_USERNAME="zswizzle00"
GITHUB_TOKEN="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"
REPO_URL="https://github.com/zswizzle00/NexusTrace.git"
cd NexusTrace
sudo docker-compose down
cd ..
sudo rm -rf NexusTrace
sudo git clone https://${GITHUB_TOKEN}@github.com/${GITHUB_USERNAME}/NexusTrace.git
cd NexusTrace
sudo docker-compose up --build -d