import { Global, Module } from '@nestjs/common';
import { LLM_PROVIDER_FACTORY, PredictionService } from './prediction.service.js';
import { RuleBasedProvider } from './rules.provider.js';

@Global()
@Module({
  // LLM_PROVIDER_FACTORY : point d'injection pour remplacer le client LLM dans les tests.
  providers: [PredictionService, RuleBasedProvider, { provide: LLM_PROVIDER_FACTORY, useValue: null }],
  exports: [PredictionService],
})
export class PredictionsModule {}
