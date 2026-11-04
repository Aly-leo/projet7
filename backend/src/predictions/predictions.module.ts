import { Global, Module } from '@nestjs/common';
import { LLM_PROVIDER_FACTORY, PredictionService } from './prediction.service.js';
import { RuleBasedProvider } from './rules.provider.js';
import { TrainedM1Provider } from './trained-m1.provider.js';

@Global()
@Module({
  // LLM_PROVIDER_FACTORY : point d'injection pour remplacer le client LLM dans les tests.
  providers: [PredictionService, RuleBasedProvider, TrainedM1Provider, { provide: LLM_PROVIDER_FACTORY, useValue: null }],
  exports: [PredictionService, TrainedM1Provider],
})
export class PredictionsModule {}
