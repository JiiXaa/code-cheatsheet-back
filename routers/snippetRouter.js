const router = require('express').Router();
const Snippet = require('../models/snippetModel');
const auth = require('../middleware/auth');

// READ
router.get('/', auth, async (req, res) => {
  try {
    const snippets = await Snippet.find({ user: req.user });
    res.json(snippets);
  } catch (err) {
    res.status(500).send();
  }
});

// CREATE
router.post('/', auth, async (req, res) => {
  try {
    const { title, desc, code } = req.body;

    // Validation

    if (!desc && !code) {
      return res.status(400).json({
        errorMessage: 'You need to enter at least a description or some code.',
      });
    }

    const newSnippet = new Snippet({
      title,
      desc,
      code,
      user: req.user,
    });

    const savedSnippet = await newSnippet.save();

    res.json(savedSnippet);
  } catch (err) {
    res.status(500).send();
  }
});

// UPDATE
router.put('/:id', auth, async (req, res) => {
  try {
    const { title, desc, code } = req.body;
    const snippetId = req.params.id;

    // validation

    if (!desc && !code) {
      return res.status(400).json({
        errorMessage: 'You need to enter at least a description or some code.',
      });
    }

    if (!snippetId)
      return res.status(400).json({
        errorMessage: 'Snippet ID not found. Please contact the developer.',
      });

    const originalSnippet = await Snippet.findById(snippetId);
    if (!originalSnippet)
      return res.status(400).json({
        errorMessage:
          'No snippet with this ID was found. Please contact the developer.',
      });

    if (originalSnippet.user.toString() !== req.user)
      return res.status(401).json({ errorMessage: 'Unauthorized' });

    originalSnippet.title = title;
    originalSnippet.desc = desc;
    originalSnippet.code = code;

    const savedSnippet = await originalSnippet.save();

    res.json(savedSnippet);
  } catch (err) {
    res.status(500).send();
  }
});

// DELETE
router.delete('/:id', auth, async (req, res) => {
  try {
    const snippetId = req.params.id;

    // validation

    if (!snippetId)
      return res.status(400).json({
        errorMessage: 'Snippet ID not found. Please contact the developer.',
      });

    const existingSnippet = await Snippet.findById(snippetId);
    if (!existingSnippet)
      return res.status(400).json({
        errorMessage:
          'No snippet with this ID was found. Please contact the developer.',
      });

    if (existingSnippet.user.toString() !== req.user)
      return res.status(401).json({ errorMessage: 'Unauthorized' });

    await existingSnippet.delete();

    res.json(existingSnippet);
  } catch (err) {
    res.status(500).send();
  }
});

module.exports = router;
