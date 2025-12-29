const test = require("node:test");
const assert = require("node:assert");
const cheerio = require("cheerio");

/**
 * Test suite for HTML sanitization used in status pages
 * This tests the specific cheerio-based text extraction that was implemented
 * to fix the incomplete multi-character sanitization vulnerability (CodeQL alert)
 */
test("Test HTML sanitization with cheerio text extraction", async (t) => {
    /**
     * Helper function that mimics the fixed sanitization logic
     * @param {string} rawDescription - Raw HTML description
     * @returns {string} Sanitized text content
     */
    const sanitizeDescription = (rawDescription) => {
        const $ = cheerio.load(rawDescription);
        $("script, style").remove();
        return $.text();
    };

    await t.test("should safely remove script tags and their content", async () => {
        const rawDescription = "<script>alert('xss')</script>Safe content";
        const descriptionText = sanitizeDescription(rawDescription);

        // Should contain only the safe content, script tag and its content should be removed
        assert.strictEqual(descriptionText, "Safe content", "Should remove script tags entirely");
        assert.ok(!descriptionText.includes("alert"), "Should not contain script content");
        assert.ok(!descriptionText.includes("<script"), "Should not contain script tag");
    });

    await t.test("should safely handle incomplete/malformed script tags", async () => {
        // This is the specific vulnerability that CodeQL detected
        // Old code: replace(/<[^>]*>/g, "") would leave "<script" in the output
        const rawDescription = "<script without closing bracket";
        const descriptionText = sanitizeDescription(rawDescription);

        // Cheerio should parse and handle this safely, removing the malformed script tag
        assert.strictEqual(descriptionText, "", "Should handle malformed script tags safely");
        assert.ok(!descriptionText.includes("<script"), "Should not contain malformed script tag");
    });

    await t.test("should handle nested HTML tags", async () => {
        const rawDescription = "<div><p>Nested <strong>HTML</strong> content</p></div>";
        const descriptionText = sanitizeDescription(rawDescription);

        // Should only contain text without any HTML tags
        assert.strictEqual(descriptionText, "Nested HTML content", "Should extract only text content");
    });

    await t.test("should handle empty descriptions", async () => {
        const rawDescription = "";
        const descriptionText = sanitizeDescription(rawDescription);

        // Should be empty string
        assert.strictEqual(descriptionText, "", "Should handle empty description gracefully");
    });

    await t.test("should handle HTML entities", async () => {
        const rawDescription = "<p>Test &lt;script&gt; entity &amp; more</p>";
        const descriptionText = sanitizeDescription(rawDescription);

        // Should decode HTML entities
        assert.strictEqual(descriptionText, "Test <script> entity & more", "Should decode HTML entities");
    });

    await t.test("should handle multiple malformed tags that old regex would miss", async () => {
        // Old vulnerable code: replace(/<[^>]*>/g, "")
        // This would leave "<script" in the output - the exact vulnerability CodeQL detected
        const rawDescription = "Text before <script alert('xss') Text after";
        const descriptionText = sanitizeDescription(rawDescription);

        // Cheerio should safely handle this, removing the malformed script tag
        assert.ok(!descriptionText.includes("<script"), "Should handle malformed tags without closing bracket");
        assert.ok(descriptionText.includes("Text before"), "Should preserve text before malformed tag");
    });

    await t.test("should handle mixed content with partial tags", async () => {
        const rawDescription = "<div>Safe</div> <script>bad</script> <p>More safe</p>";
        const descriptionText = sanitizeDescription(rawDescription);

        // Should extract all safe text content, removing script tags
        assert.ok(descriptionText.includes("Safe"), "Should include safe content");
        assert.ok(descriptionText.includes("More safe"), "Should include more safe content");
        assert.ok(!descriptionText.includes("bad"), "Should not include script content");
    });

    await t.test("should remove style tags", async () => {
        const rawDescription = "<style>.bad { color: red; }</style><p>Good content</p>";
        const descriptionText = sanitizeDescription(rawDescription);

        // Should remove style tags and their content
        assert.strictEqual(descriptionText, "Good content", "Should remove style tags");
        assert.ok(!descriptionText.includes(".bad"), "Should not include style content");
    });
});
