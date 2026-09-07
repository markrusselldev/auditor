import unittest

from auditor.textnorm import normalize_scraped_text


class TestNormalizeScrapedText(unittest.TestCase):
    def test_curly_quotes_to_straight(self):
        self.assertEqual(
            normalize_scraped_text(chr(0x2018) + "can" + chr(0x2019) + "t" + chr(0x2019)),
            "'can't'",
        )
        self.assertEqual(
            normalize_scraped_text(chr(0x201C) + "hi" + chr(0x201D)),
            '"hi"',
        )

    def test_dashes_and_ellipsis(self):
        self.assertEqual(normalize_scraped_text("a" + chr(0x2014) + "b"), "a-b")
        self.assertEqual(normalize_scraped_text("1" + chr(0x2013) + "5"), "1-5")
        self.assertEqual(normalize_scraped_text("wait" + chr(0x2026)), "wait...")

    def test_invisible_and_prime_chars(self):
        self.assertEqual(normalize_scraped_text("a" + chr(0x00A0) + "b"), "a b")
        self.assertEqual(normalize_scraped_text("a" + chr(0x200B) + "b"), "ab")
        self.assertEqual(normalize_scraped_text("5" + chr(0x2032)), "5'")

    def test_html_entities_decoded_before_mapping(self):
        # scraped HTML carries entities; decode them, THEN fold the resulting smart chars
        self.assertEqual(normalize_scraped_text("we&rsquo;re&nbsp;open"), "we're open")
        self.assertEqual(normalize_scraped_text("a&mdash;b&hellip;"), "a-b...")
        self.assertEqual(normalize_scraped_text("say &#8220;hi&#8221;"), 'say "hi"')

    def test_output_is_ascii_for_typical_scraped_text(self):
        messy = "Oops&mdash;this site can" + chr(0x2019) + "t be reached&hellip;"
        out = normalize_scraped_text(messy)
        self.assertTrue(out.isascii())
        self.assertEqual(out, "Oops-this site can't be reached...")

    def test_empty_and_plain_passthrough(self):
        self.assertEqual(normalize_scraped_text(""), "")
        self.assertEqual(normalize_scraped_text("plain ascii - fine"), "plain ascii - fine")


if __name__ == "__main__":
    unittest.main()
