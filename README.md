# osx_pdf_reporter
- [ ]  docker build . -t osx_reporter
- [ ]  docker run —rm —mount type=bind,src=<path_to_data>,dst=/output osx_reporter

Good to be in the output data folder, then its possible to run this command as is:
- [ ]  docker run --rm --mount type=bind,src="$(pwd)",dst=/output osx_reporter -v

- [ ]  (dev command) docker run -it --rm --name=osxreporter osxreporter /bin/bash
