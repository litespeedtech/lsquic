setlocal EnableDelayedExpansion

pushd c:\tools\vcpkg

git remote update

git status -uno | findstr /c:"Your branch is up to date with 'origin/master'"

if errorlevel 1 (

	echo Updating vcpkg...

	git pull

	git reset --hard HEAD

	bootstrap-vcpkg.bat

)

git clean -fdx -e installed -e packages

popd
