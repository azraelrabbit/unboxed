#!/bin/bash

function die_with { echo "$*" >&2; exit 1; }

echo "Are you Travis?"
if [ ! $TRAVIS ]; then die_with "You are not Travis!"; fi

echo "Checking if commit is a pull request"
if [ $TRAVIS_PULL_REQUEST == true ]; then die_with "Skipping deployment for pull request!"; fi

echo "Configuring git credentials"
git config --global user.email "travis@travis-ci.org" || die_with "Failed to configure git user email!"
git config --global user.name "Travis" || die_with "Failed to configure git user name!"

echo "Cloning Snapshots repo using token"
GIT_REPO="https://$GITHUB_TOKEN@github.com/OxideMod/Snapshots.git"
git clone -q --depth 1 $GIT_REPO $HOME/Snapshots >/dev/null || die_with "Failed to clone Snapshots repository!"

echo "Copying target files to snapshots directory"
cp -f Unboxed/bin/Release/Unboxed.exe $HOME/snapshots || die_with "Failed to copy Unboxed.exe to snapshots!"

echo "Adding and committing"
cd $HOME/Snapshots || die_with "Failed to change to Snapshots directory!"
git add . || die_with "Failed to add files for commit!"
COMMIT_MESSAGE="Unboxed build $TRAVIS_BUILD_NUMBER from https://github.com/$TRAVIS_REPO_SLUG/commit/${TRAVIS_COMMIT:0:7}"
git commit -m "$COMMIT_MESSAGE" || die_with "Failed to commit files!"

git config http.postBuffer 52428800
git config pack.windowMemory "32m"
git repack --max-pack-size=100M -a -d

echo "Deploying to GitHub"
ATTEMPT=0
until [ $ATTEMPT -ge 5 ]; do
    git pull && git push -q origin master >/dev/null && break
    ATTEMPT=$[$ATTEMPT+1]
    sleep 15
done || die_with "Failed to push to GitHub!"

echo "Deployment cycle completed. Happy developing!"
