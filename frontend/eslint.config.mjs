// @ts-check
import eslint from '@eslint/js';
import angular from 'angular-eslint';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    files: ['**/*.ts'],
    extends: [eslint.configs.recommended, ...tseslint.configs.recommended, ...angular.configs.tsRecommended],
    processor: angular.processInlineTemplates,
    rules: {
      '@angular-eslint/directive-selector': ['error', { type: 'attribute', prefix: 'app', style: 'camelCase' }],
      '@angular-eslint/component-selector': ['error', { type: 'element', prefix: 'app', style: 'kebab-case' }],
      // Exigence de sécurité : aucune contournement de l'assainissement Angular, aucun HTML dynamique, aucun eval.
      'no-restricted-syntax': [
        'error',
        { selector: "CallExpression[callee.property.name=/^bypassSecurityTrust/]", message: 'bypassSecurityTrust* est interdit (XSS).' },
        { selector: "Identifier[name=/^bypassSecurityTrust/]", message: 'bypassSecurityTrust* est interdit (XSS).' },
        { selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]", message: 'innerHTML est interdit : affichez les données externes comme texte.' },
        { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: 'insertAdjacentHTML est interdit.' },
      ],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
  {
    files: ['**/*.html'],
    extends: [...angular.configs.templateRecommended],
    rules: {},
  },
  { files: ['**/*.ts'], ignores: ['src/**'], rules: {} },
);
