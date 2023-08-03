# type: ignore

# This file will NOT be run from inside the rocky python path. It will instead be run inside the
# apps/firefox Nix pkgset.

# This script should be invoked like:
# python3 web_selenium.py <JSON BLOB WITH OPTIONS>
# That is, the json blob with options is given as a command-line argument.
# The JSON blob should contain the following:
# {
#    "browser": "firefox" | "chrome", // the browser to use
#    "headless": bool, // should the browser be headless or not
#    "verbose_logs": bool, // if true, then have verbose logs
#    "scenario": str, // the name of a scenario to run
#    // Specific scenarios may have additional arguments.
# }

# python3 testing/apps/web_selenium.py '{"browser": "firefox", "headless": false, "verbose_logs": true, "scenario": "badssl"}'

if __name__ == "__main__":
    import json
    import os
    import signal
    import sys
    import time
    from pathlib import Path
    from shutil import rmtree, which
    from subprocess import check_call

    from selenium.common.exceptions import InsecureCertificateException

    assert len(sys.argv) == 2
    args = json.loads(sys.argv[1])

    def scenario_badssl(driver):
        try:
            driver.get("https://self-signed.badssl.com/")
            driver.implicitly_wait(10)
            driver.find_element_by_id("content")
            raise AssertionError("The page should not have properly loaded.")
        except InsecureCertificateException:
            # This is what we're looking for.
            pass

    def scenario_example_com(driver):
        driver.get("https://www.example.com/")
        driver.implicitly_wait(10)
        h1 = driver.find_element_by_css_selector("h1")
        assert h1.text == "Example Domain"

    def scenario_plaintext_load(driver):
        driver.get(args["url"])
        driver.implicitly_wait(10)
        pre = driver.find_element_by_css_selector("pre")
        assert len(pre.text) > 10

    def scenario_plik_just_upload(driver):
        driver.get(args["url"])
        driver.implicitly_wait(10)
        driver.find_element_by_css_selector("#ngf-drop-zone").send_keys(
            args["file_to_upload"]
        )
        driver.find_element_by_css_selector(".btn-success").click()
        # Wait for the download link to appear
        driver.find_element_by_css_selector(".file-name")
        time.sleep(5)

    def scenario_play_dash(driver):
        driver.get(args["url"])
        # Firefox disables autoplay by default. We need to manually click the video.
        time.sleep(5)
        driver.find_element_by_css_selector("video").click()
        time.sleep(args["sleep"])

    SCENARIOS = {
        "badssl": scenario_badssl,
        "example.com": scenario_example_com,
        "plaintext-load": scenario_plaintext_load,
        "plik-just-upload": scenario_plik_just_upload,
        "play-dash": scenario_play_dash,
    }
    assert args["scenario"] in SCENARIOS

    if args["browser"] == "firefox":
        from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
        from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
        from selenium.webdriver.firefox.options import Options
        from selenium.webdriver.firefox.webdriver import WebDriver

        class OurFirefoxBinary(FirefoxBinary):
            # If it doesn't start with an underscore, it's in the public API :)
            # Selenium wants to dynamic-library inject into firefox. The problem is that it will try
            # (and fail) to dynamically inject into our bash wrapper. So we just disable the dynamic
            # library injection.
            NO_FOCUS_LIBRARY_NAME = "/dev/null"

        def raise_keyboard_interrupt(sig, frame):
            raise KeyboardInterrupt()

        signal.signal(signal.SIGTERM, raise_keyboard_interrupt)

        BIN = which("rockyFirefoxDylibInjection")
        assert BIN is not None

        firefox_bin = OurFirefoxBinary(BIN, log_file=sys.stdout)
        options = Options()
        options.headless = args["headless"]
        if args["verbose_logs"]:
            options.log.level = "trace"
        options.accept_insecure_certs = True  # TODO
        profile = FirefoxProfile()
        try:
            # TODO: disable dns over https?
            profile.accept_untrusted_certs = True  # TODO
            # Setup the certificate store.
            # TODO: cache this setup (it takes 2 seconds on my laptop!)
            for i, entry in enumerate(
                Path(os.environ["NIX_SSL_CERT_FILE"]).read_text().strip().split("\n\n")
            ):
                if "-----BEGIN TRUSTED CERTIFICATE-----" in entry:
                    continue
                lines = entry.split("\n")
                name = lines[0]
                del lines[0]
                cert = "\n".join(lines)
                profile_path = Path(profile.path)
                tmp_cert = profile_path / "tmp.crt"
                tmp_cert.write_text(cert)
                check_call(
                    [
                        "certutil",
                        "-A",
                        "-n",
                        "%s%d" % (name, i),
                        "-t",
                        "TC,Cw,Tw",
                        "-i",
                        str(tmp_cert),
                        "-d",
                        str(profile_path),
                    ]
                )
                tmp_cert.unlink()
            firefox = WebDriver(
                firefox_profile=profile,
                firefox_binary=firefox_bin,
                options=options,
                # in newer versions of selenium, this needs to be set on a Service object, passed to the
                # service argument.
                service_log_path=None,
            )
            firefox.service.log_file = sys.stdout
            try:
                SCENARIOS[args["scenario"]](firefox)
            finally:
                firefox.quit()
        finally:
            rmtree(profile.path, ignore_errors=True)
    else:
        raise Exception("Unknown browser.")
