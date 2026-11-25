import tempfile
import unittest
import zipfile
from pathlib import Path

from dby2_rootctl.bootstrap import MagiskBootstrap, parse_magisk_package_info


class BootstrapParsingTests(unittest.TestCase):
    def test_parses_magisk_package_info(self) -> None:
        raw_output = (
            "    userId=10337\n"
            "    codePath=/data/app/example/com.topjohnwu.magisk/base\n"
            "    primaryCpuAbi=arm64-v8a\n"
            "    versionName=31.1\n"
        )

        info = parse_magisk_package_info(raw_output)

        self.assertEqual(info.uid, 10337)
        self.assertEqual(
            info.native_directory,
            "/data/app/example/com.topjohnwu.magisk/base/lib/arm64",
        )
        self.assertEqual(info.version_name, "31.1")

    def test_reads_module_id_from_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            module_zip = Path(temporary) / "module.zip"
            with zipfile.ZipFile(module_zip, "w") as archive:
                archive.writestr("module.prop", "id=zygisk_vector\nname=Vector\n")

            module_id = MagiskBootstrap._read_module_id(module_zip)

        self.assertEqual(module_id, "zygisk_vector")


if __name__ == "__main__":
    unittest.main()
