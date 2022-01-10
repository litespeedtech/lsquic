setlocal EnableDelayedExpansion

pushd c:\tools\vcpkg

git remote update

git status -uno | findstr /c:"Your branch is up to date with 'origin/master'"

if errorlevel 1 (

	echo Updating vcpkg...

	git pull -q

	git reset -q --hard HEAD

	bootstrap-vcpkg.bat

)

git clean -qfdx -e installed -e packages

popd
