"""The shared role that creates fixed-size ext4 images."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "capped_volume"


class CappedVolumeRoleTests(unittest.TestCase):
    def test_a_capped_image_keeps_its_reservation(self) -> None:
        # mkfs.ext4 on a regular file discards blocks by punching holes, which turns the
        # fallocated image sparse. A sparse image grows into the root disk past the margin
        # the role checked, and host_filesystem_untouched fails.
        image = (ROLE / "tasks" / "volume.yml").read_text(encoding="utf-8")
        formats = image.split("      - mkfs.ext4\n")[1:]
        self.assertEqual(len(formats), 2)
        for body in formats:
            argv = body.split("when:", 1)[0]
            self.assertIn("-E", argv)
            self.assertIn("nodiscard", argv)
            # With lazy init the kernel zeroes the inode tables after the mount, and on a
            # loop device that punches holes in the file again (measured: 4 MiB of 2 GiB).
            self.assertIn("lazy_itable_init=0", argv)
            self.assertIn("lazy_journal_init=0", argv)
        prealloc = image.split("- name: Preallocate an image that is sparse", 1)[1].split("- name:", 1)[0]
        self.assertIn("fallocate", prealloc)
        # The decision uses the disk usage read after the reservation, not a stale stat.
        self.assertIn("disk_usage_bytes", prealloc)
        before = image.split("- name: Preallocate an image that is sparse", 1)[0]
        self.assertIn("- name: Stat the image before preallocation", before)
        # mkfs zeroes the inode tables by punching holes in the file, so the top-up
        # must come after the format, or the next run finds holes and changes again.
        stat_at = before.index("- name: Stat the image before preallocation")
        self.assertGreater(stat_at, before.index("- name: Format a new image without an inode cap"))
        self.assertGreater(stat_at, before.index("- name: Require the new filesystem to be ext4"))
        self.assertIn("changed_when: true", prealloc)
        self.assertNotIn("changed_when: false", prealloc)

    def test_the_role_does_not_resize_or_reformat_an_existing_image(self) -> None:
        image = (ROLE / "tasks" / "volume.yml").read_text(encoding="utf-8")
        self.assertIn("does not resize an existing image", image)
        self.assertIn("A probe failure or a foreign filesystem is not formatted", image)

    def test_the_owner_comes_from_the_item_and_not_from_a_pin(self) -> None:
        image = (ROLE / "tasks" / "volume.yml").read_text(encoding="utf-8")
        self.assertIn('owner: "{{ capped.owner }}"', image)
        for path in ROLE.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("g2_pins", text, str(path.relative_to(ROLE)))

    def test_the_margin_check_runs_before_any_image_is_created(self) -> None:
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertLess(main.index("Require the root margin"), main.index("include_tasks: volume.yml"))
        self.assertIn("capped_volume_root_margin_percent", main)

    def test_the_mount_unit_is_fail_soft_and_hardened(self) -> None:
        unit = (ROLE / "templates" / "capped.mount.j2").read_text(encoding="utf-8")
        self.assertIn("loop,nodev,nosuid,nofail", unit)
        self.assertIn("RequiresMountsFor={{ capped.image }}", unit)

    def test_the_inputs_are_validated(self) -> None:
        spec = (ROLE / "meta" / "argument_specs.yml").read_text(encoding="utf-8")
        for key in ("image", "mount", "bytes", "unit", "mode", "owner", "fs_label"):
            self.assertIn(f"{key}:", spec)


if __name__ == "__main__":
    unittest.main()
