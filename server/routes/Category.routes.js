const express = require("express");
const router = express.Router();
const categoriesController = require("../controllers/categoriesController");

// Obtenir toutes les catégories
router.get("/", categoriesController.getCategories);

// Ajouter une nouvelle catégorie
router.post("/", categoriesController.createCategory);

// Supprimer une catégorie par ID
router.delete("/:id", categoriesController.deleteCategory);

// Mettre à jour une catégorie par ID (ajouter un groupe ou un item)
router.put("/:id", categoriesController.updateCategory);

module.exports = (app) => app.use("/api/categories", router);
